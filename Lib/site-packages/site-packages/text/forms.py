from django import forms

from .models import Text
from .widgets import HTMLEditorWidget


class TextForm(forms.ModelForm):
    class Meta:
        model = Text
        exclude = ['language']

    def __init__(self, *args, **kwargs):
        super(TextForm, self).__init__(*args, **kwargs)
        self.fields['name'].widget = forms.HiddenInput()
        self.fields['body'].widget = HTMLEditorWidget()
