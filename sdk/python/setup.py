from setuptools import setup, find_packages

setup(
    name="guardianai-sdk",
    version="1.0.0",
    description="GuardianAI Python SDK and Dynamic Client-Wrapping Middleware",
    long_description=open("README.md").read() if open("README.md") else "",
    long_description_content_type="text/markdown",
    author="GuardianAI Security Labs",
    author_email="security@guardianai.com",
    url="https://github.com/GuardianAI/guardianai-basic-launch",
    packages=find_packages(),
    py_modules=["guardianai"],
    install_requires=[],
    extras_require={
        "openai": ["openai>=1.0.0"],
        "anthropic": ["anthropic>=0.3.0"],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
    ],
    python_requires=">=3.8",
)
