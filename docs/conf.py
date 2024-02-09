# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information
import os
import sys

sys.path.insert(0, os.path.abspath('..'))



project = 'oauth2'
copyright = '2024, Nihar Ranjan Mohanty'
author = 'Nihar Ranjan Mohanty'
release = '0.0000'

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = ['sphinx.ext.autodoc']

templates_path = ['_templates']
exclude_patterns = []



# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = 'sphinx_rtd_theme'

html_theme_options = {
    'canonical_url': '',
    'analytics_id': 'UA-XXXXXXX-1',  # Google Analytics ID
    'logo_only': False,
    'display_version': True,
    'prev_next_buttons_location': 'bottom',
    'style_external_links': False,
    # Toc options
    'collapse_navigation': True,
    'sticky_navigation': True,
    'navigation_depth': 3,
    'includehidden': True,
    'titles_only': False
}

html_sidebars = {
    '**': [
        'searchbox.html',  # Include search box
        'globaltoc.html',  # Include table of contents
        'sourcelink.html',  # Optional: Include source code links
    ]
}



html_static_path = ['_static']


os.environ['DJANGO_SETTINGS_MODULE'] = 'oauth2.settings'

import django
django.setup()

# Import views.py from your Django app
from oauth2app import views