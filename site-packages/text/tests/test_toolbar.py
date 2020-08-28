from django.contrib.staticfiles.testing import StaticLiveServerTestCase
from django.contrib.auth.models import User

from selenium import webdriver
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions

from text.models import Text
from .utils import override_conf


class TestToolbar(StaticLiveServerTestCase):
    @classmethod
    def setUpClass(cls):
        super(TestToolbar, cls).setUpClass()
        cls.selenium = webdriver.PhantomJS()
        cls.selenium.set_window_size(1280, 600)

    @classmethod
    def tearDownClass(cls):
        cls.selenium.quit()
        super(TestToolbar, cls).tearDownClass()

    def setUp(self):
        self.user = User.objects.create_superuser(
            'adm', 'adm@example.com', 'pw')
        self.user.save()

    def authenticate(self):
        self.selenium.get(self.live_server_url + '/admin/')
        login_page = self.selenium.find_element_by_tag_name('html')
        self.selenium.find_element_by_id('id_username').send_keys('adm')
        self.selenium.find_element_by_id('id_password').send_keys('pw')
        self.selenium.find_element_by_css_selector('[type=submit]').click()
        WebDriverWait(self.selenium, 3).until(
            expected_conditions.staleness_of(login_page))

    def edit_set_text(self, text):
        self.selenium.get(self.live_server_url + '/tag/')
        self.selenium.find_element_by_id('djtext_toolbar_handle').click()
        menu_li = self.selenium.find_element_by_css_selector(
            '.djtext_menu ul li')
        WebDriverWait(self.selenium, 3).until(
            expected_conditions.visibility_of(menu_li))
        menu_li.click()
        self.assertEqual(
            self.selenium.find_element_by_class_name('djtext_text_name').text,
            "a_text_node_en-us")
        textarea = self.selenium.find_element_by_class_name(
            'djtext_editor_input')
        textarea.clear()
        textarea.send_keys(text)
        self.selenium.find_element_by_class_name('djtext_submit').click()

    @override_conf(TOOLBAR_INSTANT_UPDATE=False)
    def test_edit(self):
        self.authenticate()
        self.edit_set_text('hello!')
        self.assertTrue(
            self.selenium.find_element_by_id(
                'djtext_reload_page_notice').is_displayed())
        self.assertEqual(Text.objects.get().render(), 'hello!')

    @override_conf(TOOLBAR_INSTANT_UPDATE=True)
    def test_edit_instant(self):
        self.authenticate()
        self.edit_set_text('hola')
        self.assertEqual(Text.objects.get().render(), 'hola')
        self.assertNotIn(
            'djtext_toggle',
            self.selenium.find_element_by_id(
                'djtext_toolbar').get_attribute('class'))
        self.assertTrue(
            self.selenium.find_element_by_css_selector(
                '[data-text-name=a_text_node]').text, 'hola')
