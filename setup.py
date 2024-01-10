from setuptools import find_packages, setup

version = '0.1.0-alpha'

setup(
    name='alerta-zammad',
    version=version,
    description='Alerta plugin for Zammad Ticket Creation',
    url='https://github.com/mapel/alerta-zammad',
    license='MIT',
    author='Michael Diesen',
    author_email='michael.diesen@posteo.de',
    packages=find_packages(),
    py_modules=['alerta_zammad'],
    install_requires=[

    ],
    include_package_data=True,
    zip_safe=True,
    entry_points={
        'alerta.plugins': [
            'zammad = alerta_zammad:TriggerEvent'
        ]
    }
)