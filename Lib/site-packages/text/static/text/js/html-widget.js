(function ($) {
    "use strict";

    function get_editor(editor_element, textarea) {
        var editor = new MediumEditor(editor_element.get(), {
                firstHeader: 'h1',
                secondHeader: 'h2'
            }),
            el = $(editor.elements[0]);

        editor.subscribe('editableInput', function () {
            textarea.val(editor.serialize()['element-0'].value);
            el.find("span[style]").each(function (_, sp) {
                sp = $(sp);
                sp.before(sp.contents()).remove();
            });
        });

        return editor;
    }

    $(function () {
        var textarea = $(".djtext_editor_input"),
            editor_element = $(".djtext_html_editor"),
            type_select = editor_element.parents('form').find('[id$="type"]'),
            editor;

        function set_mode(mode) {
            if (mode == 'html') {
                textarea.hide();
                editor_element.show();
                editor = get_editor(editor_element, textarea);
            } else {
                textarea.show();
                editor_element.hide();
            }
        }

        set_mode(type_select.val());

        type_select.bind('change', function () {
            set_mode(type_select.val());
        });
    });

}(window.Zepto));
