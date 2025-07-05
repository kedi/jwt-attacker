from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="jwt-attacker",
    version="0.1.0",
    author="JWT Attacker Tool",
    author_email="furkan@wearehackerone.com",
    description="A Python-based toolkit for testing JWT security vulnerabilities",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/kedi/jwt-attacker",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: Security :: Cryptography",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "jwt-attacker=jwt_attacker.main:main",
        ],
    },
    include_package_data=True,
    keywords="jwt, security, penetration-testing, authentication, token, brute-force",
)
