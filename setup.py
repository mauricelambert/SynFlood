from setuptools import setup

setup(
    name="SynFlood",
    version="1.0.0",
    py_modules=["SynFlood"],
    install_requires=["scapy"],
    author="Maurice Lambert",
    author_email="mauricelambert434@gmail.com",
    maintainer="Maurice Lambert",
    maintainer_email="mauricelambert434@gmail.com",
    description="This package implements a SYN flood attack (DOS attack: Denial Of Service).",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/mauricelambert/SynFlood",
    project_urls={
        "Documentation": "https://mauricelambert.github.io/info/python/security/SynFlood.html",
        "Executable": "https://mauricelambert.github.io/info/python/security/SynFlood.pyz",
    },
    classifiers=[
        "Programming Language :: Python",
        "Development Status :: 5 - Production/Stable",
        "Topic :: System :: Networking",
        "Topic :: Security",
        "Natural Language :: English",
        "Programming Language :: Python :: 3.9",
        "Operating System :: POSIX :: Linux",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: MacOS",
    ],
    python_requires=">=3.8",
    entry_points={
        "console_scripts": ["SynFlood = SynFlood:main"],
    },
    keywords=[
        "DOS",
        "DenialOfService",
        "SYN",
        "flood",
        "SYNflood",
    ],
    platforms=["Windows", "Linux", "MacOS"],
    license="GPL-3.0 License",
)
