# Path to the project module
import os
import sys
sys.path.insert(0, os.path.abspath('..'))

# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

# Read the version in the __version__.py file
def read_version():
    version_file = os.path.join(os.path.dirname(__file__), '..', 'encryption', '__version__.py')
    with open(version_file) as f:
        exec(f.read()) 
    return locals()['__version__']

project = 'encryption'
copyright = '2024, Artezaru'
author = 'Artezaru'
release = read_version()

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.viewcode',
]

templates_path = ['_templates']
exclude_patterns = []

# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = 'alabaster'
html_static_path = ['_static']


# Import the Read the Docs theme
import sphinx_rtd_theme

# The theme to use for HTML and HTML Help pages. (default: 'alabaster')
html_theme = 'sphinx_rtd_theme'

# Add any paths that contain custom themes here, relative to this directory.
html_theme_path = []

# Add the extensions
extensions = [
'sphinx.ext.autodoc',
'sphinx.ext.viewcode',  # Optional: to add links to the source code in the documentation
# Add other extensions you want
]