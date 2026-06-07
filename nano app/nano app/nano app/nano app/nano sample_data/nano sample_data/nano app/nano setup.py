from setuptools import setup, find_packages

setup(
    name='cdr-ipdr-analyzer',
    version='1.0.0',
    description='CDR/IPDR Examination & Analysis Tool',
    author='HackerAI',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'Flask>=3.0',
        'pandas>=2.0',
        'numpy>=1.24',
        'matplotlib>=3.7',
        'seaborn>=0.12',
        'folium>=0.15',
        'networkx>=3.0',
        'openpyxl>=3.1',
        'gunicorn>=23.0',
    ],
    entry_points={
        'console_scripts': [
            'cdr-analyzer=run:main',
        ],
    },
)
