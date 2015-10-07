#########
# Copyright (c) 2015 GigaSpaces Technologies Ltd. All rights reserved
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
#  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  * See the License for the specific language governing permissions and
#  * limitations under the License.

from setuptools import setup


def get_long_description():
    with open('README.md') as f:
        txt = f.read()
    return txt


setup(
    name='Flask-SecuREST',
    version='0.6',
    url='https://github.com/cloudify-cosmo/flask-securest/',
    license='LICENSE',
    author='cosmo-admin',
    author_email='cosmo-admin@gigaspaces.com',
    description='Simple framework for securing Flask REST applications',
    long_description=get_long_description(),
    packages=['flask_securest',
              'flask_securest.authentication_providers',
              'flask_securest.authorization_providers',
              'flask_securest.userstores',
              'flask_securest.acl_handlers'],
    zip_safe=False,
    install_requires=[
        'Flask>=0.9',
        'Flask-RESTful>=0.2.5',
        'passlib>=1.6.2',
        'itsdangerous>=0.24',
    ],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ]
)
