from distutils.core import setup

setup(
    name="containersecurity-event-query",
    packages=["containersecurity-event-query"],
    version="0.0.1",
    license="MIT",
    description="Helper Tools For Cloud One Container Security",
    long_description=" ".join(
        ["Lightweight Python 3 to ease policy and event management in Cloud One Container Security"],
    ),
    author="Markus Winkler",
    author_email="winkler.info@icloud.com",
    url="https://github.com/mawinkler/containersecurity-event-query",
    keywords=["Cloud One", "Container Security", "Python"],
    install_requires=["prettytable", "requests"],
    classifiers=[
        # Chose either "3 - Alpha", "4 - Beta" or "5 - Production/Stable" as the current state of your package
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Build Tools",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
    ],
)
