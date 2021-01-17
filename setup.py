from setuptools import setup, find_packages

setup(
    name = 'SynFlood',
 
    version = "0.0.1",
    packages = find_packages(include=["SynFlood"]),
    install_requires = ['scapy'],

    author = "Maurice Lambert", 
    author_email = "mauricelambert434@gmail.com",
 
    description = "This package implement a DOS (Denial Of Service) tool in python (SYN Flood).",
    long_description = open('README.md').read(),
    long_description_content_type="text/markdown",
 
    include_package_data = True,

    url = 'https://github.com/mauricelambert/SynFlood',
 
    classifiers = [
        "Programming Language :: Python",
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Natural Language :: English",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3.8"
    ],
 
    entry_points = {
        'console_scripts': [
            'SynFlood = SynFlood:launcher'
        ],
    },
    python_requires='>=3.6',
)
