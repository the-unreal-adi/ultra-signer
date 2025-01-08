from setuptools import setup, find_packages

setup(
    name='windows-service-project',
    version='0.1',
    packages=find_packages(where='src'),
    package_dir={'': 'src'},
    install_requires=[
        'PyKCS11',
        'Flask',  # Assuming Flask is used for jsonify
        # Add other dependencies as needed
    ],
    entry_points={
        'console_scripts': [
            'windows-service=service:main',  # Replace 'main' with the actual entry function if different
        ],
    },
    author='Your Name',
    author_email='your.email@example.com',
    description='A Windows service for managing PKCS#11 tokens and digests.',
    license='MIT',
    keywords='windows service pkcs11',
    url='https://github.com/yourusername/windows-service-project',  # Replace with your repository URL
)