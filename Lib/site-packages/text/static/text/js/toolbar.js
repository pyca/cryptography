(function ($) {
    "use strict";

    function DOMLazyElement(selector, context) {
        var el = null;
        return function () {
            if (el === null) {
                if (Array.isArray(selector)) {
                    selector = selector[0];
                    context = selector[1];
                }
                el = $(selector, context);
            }
            return el;
        };
    }

    function DOMLazyElements(selectors) {
        var registry = {};
        for (var name in selectors) {
            if (selectors.hasOwnProperty(name)) {
                registry[name] = DOMLazyElement(selectors[name]);
            }
        }
        return registry;
    }

    var form = $('#djtext_form'),
        toolbar = $('#djtext_toolbar'),
        lazy = DOMLazyElements({
            'body': 'body',
            'handle': '#djtext_toolbar_handle',
            'closer': '.djtext_close_toolbar',
            'menu_items': '.djtext_menu li',
            'editor': '.djtext_editor',
            'editor_element': '.djtext_html_editor',
            'content_element': '.djtext_editor_input',
            'csrf_input': ['[name=csrfmiddlewaretoken]', form],
            'name_element': '.djtext_text_name',
            'start_element': '.djtext_editor_start',
            'submit': '.djtext_submit',
            'menu': '.djtext_toolbar_menu',
            'tools': '.djtext_toolbar_menu_tools',
            'reload_page_notice': '#djtext_reload_page_notice'
        }),
        language = toolbar.data('language'),
        url_get_pattern = toolbar.data('url-pattern'),
        toolbar_active = false,
        url_post_pattern = form.attr('action'),
        text_id = null,
        text_name = null;

    function toggle_toolbar() {
        if (toolbar_active) {
            toolbar.removeClass('djtext_toggle');
            lazy.menu().hide();
            lazy.body().css('overflow', 'visible');
        } else {
            toolbar.addClass("djtext_toggle");
            lazy.menu().show();
            lazy.body().css('overflow', 'hidden');
        }
        toolbar_active = !toolbar_active;
    }

    function init_toolbar_handles() {
        lazy.handle().on('click', toggle_toolbar);
        lazy.closer().on('click', toggle_toolbar);
    }

    function get_text_slug(name) {
        return name + '_' + language;
    }

    function get_url(name) {
        return url_get_pattern.replace('__id__', get_text_slug(name));
    }

    function post_url() {
        return url_post_pattern.replace('0', text_id);
    }

    function update_editor(text_data) {
        Object.keys(text_data).forEach(function (key) {
            $('#id_djtext_form-' + key, form).val(text_data[key]).change();
        });
        form.attr('action', post_url(text_data.name));
        lazy.name_element().text(get_text_slug(text_data.name));
        lazy.editor_element().html(text_data.render).focus();
        lazy.start_element().hide();
        lazy.editor().show();
        lazy.tools().css('opacity', 1);
    }

    function load_text() {
        var menu_item = $(this),
            name = menu_item.data('name'),
            url = get_url(name);
        lazy.reload_page_notice().hide();
        $.getJSON(url, function (response) {
            update_editor(response);
            toolbar.scrollTop(0);
            text_id = response.id;
            text_name = response.name;
        });
    }

    function save_form() {
        $.ajax({
            url: post_url(),
            type: 'POST',
            data: form.serialize(),
            dataType: 'JSON',
            headers: {
                'X-CSRFToken': lazy.csrf_input().val()
            },
            success: function () {
                var el = $('.' + toolbar.data('inline-wrapper-class') + '[data-text-name="' + text_name + '"]'),
                    updatable = el.length > 0;
                if (updatable) {
                    el.html(lazy.content_element().val());
                    toggle_toolbar();
                } else {
                    lazy.reload_page_notice().show();
                }
            }
        });
    }

    function init_form() {
        form.on('submit', function (e) {
            e.preventDefault();
            save_form();
            return false;
        });

        lazy.submit().click(function() {
            form.submit();
        });
    }

    function init_text_menu() {
        lazy.menu_items().on('click', load_text);
    }

    function init() {
        init_toolbar_handles();
        init_text_menu();
        init_form();
    }

    $(init);
}(Zepto));
