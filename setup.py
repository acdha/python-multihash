from setuptools import setup

setup(
    name='multihash',
    use_scm_version=True,
    setup_requires=['setuptools_scm'],
    py_modules=['multihash'],
    author='Wijnand Modderman-Lenstra',
    author_email='maze@pyth0n.org',
    maintainer='Wijnand Modderman-Lenstra',
    maintainer_email='maze@pyth0n.org',
    url='https://github.com/tehmaze/python-multihash',
    keywords='multihash',
    platforms='POSIX, Windows',
    license='MIT',
    description='multihash implementation in Python',
    install_requires=[
        'sha3;python_version<"3.6"',
        'pyblake2;python_version<"3.6"',
    ]
)
