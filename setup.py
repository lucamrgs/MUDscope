import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="mudscope",
    version="0.0.1",
    author="Luca Morgese Zangrandi",
    author_email="luca.morgese@tno.nl",
    description="MUDscope - Stepping out of the MUD: Contextual threat information for IoT devices with manufacturer-provided behaviour profiles",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/lucamrgs/MUDscope",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
