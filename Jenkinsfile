/* known issues */
/* Parallel tasks, when executed, show up as "part of <job name>" rather than a more descriptive name. See http://stackoverflow.com/questions/37812588/how-can-i-override-the-part-of-app-pipeline-buildname */

/* notes */
/* You must escape backslashes because groovy. */

/* TODO */
/* expand macOS testing */
/* IRC notification on master merge */
/* smoke tests */


def configs = [
    /* [ */
    /*     label: 'windows', */
    /*     toxenvs: ['py26', 'py27', 'py33', 'py34', 'py35', 'py36'], */
    /* ], */
    /* [ */
    /*     label: 'windows64', */
    /*     toxenvs: ['py26', 'py27', 'py33', 'py34', 'py35', 'py36'], */
    /* ], */
    /* [ */
    /*     label: 'freebsd11', */
    /*     toxenvs: ['py27'], */
    /* ], */
    /* [ */
    /*     label: 'sierra', */
    /*     toxenvs: ['py27'], */
    /* ], */
    /* [ */
    /*     label: 'docker', */
    /*     image_name: 'pyca/cryptography-runner-centos7', */
    /*     toxenvs: ['py27'], */
    /* ], */
    /* [ */
    /*     label: 'docker', */
    /*     image_name: 'pyca/cryptography-runner-wheezy', */
    /*     toxenvs: ['py27'], */
    /* ], */
    /* [ */
    /*     label: 'docker', */
    /*     image_name: 'pyca/cryptography-runner-jessie', */
    /*     toxenvs: ['py27', 'py34'], */
    /* ], */
    /* [ */
    /*     label: 'docker', */
    /*     image_name: 'pyca/cryptography-runner-sid', */
    /*     toxenvs: ['py27', 'py35'], */
    /* ], */
    /* [ */
    /*     label: 'docker', */
    /*     image_name: 'pyca/cryptography-runner-stretch', */
    /*     toxenvs: ['py27', 'py35'], */
    /* ], */
    /* [ */
    /*     label: 'docker', */
    /*     image_name: 'pyca/cryptography-runner-jessie-libressl:2.4.5', */
    /*     toxenvs: ['py27'], */
    /* ], */
    /* [ */
    /*     label: 'docker', */
    /*     image_name: 'pyca/cryptography-runner-ubuntu-xenial', */
    /*     toxenvs: ['py27', 'py35'], */
    /* ], */
    /* [ */
    /*     label: 'docker', */
    /*     image_name: 'pyca/cryptography-runner-ubuntu-rolling', */
    /*     toxenvs: ['py27', 'py35'], */
    /* ], */
    [
        label: 'docker',
        image_name: 'pyca/cryptography-runner-fedora',
        toxenvs: ['py27', 'py35'],
    ],
]

def checkout_git() {
    if (env.BRANCH_NAME.startsWith('PR-')) {
        def script = """
        git clone --depth=1 https://github.com/pyca/cryptography.git cryptography
        cd cryptography
        git fetch origin +refs/pull/${env.CHANGE_ID}/merge:
        git checkout -qf FETCH_HEAD
        """
    } else {
        def script = """
        git clone --depth=1 https://github.com/pyca/cryptography.git cryptography
        cd cryptography
        git checkout ${env.BRANCH_NAME}
        """
    }
    if (label.contains("windows")) {
        bat script
    } else {
        sh script
    }
}
def build(toxenv, label, image_name) {

    try {
        timeout(time: 30, unit: 'MINUTES') {
            withCredentials([string(credentialsId: 'cryptography-codecov-token', variable: 'CODECOV_TOKEN')]) {
                if (label.contains("windows")) {
                    bat """
                        @set PATH="C:\\Python27";"C:\\Python27\\Scripts";%PATH%
                        @set CRYPTOGRAPHY_WINDOWS_LINK_OPENSSL110=1
                        if $toxenv == py26 (
                            @set PYTHON="C:\\Python26\\python.exe"
                        )
                        if $toxenv == py27 (
                            @set PYTHON="C:\\Python27\\python.exe"
                        )
                        if $toxenv == py33 (
                            @set PYTHON="C:\\Python33\\python.exe"
                        )
                        if $toxenv == py34 (
                            @set PYTHON="C:\\Python34\\python.exe"
                        )
                        if $toxenv == py35 (
                            @set PYTHON="C:\\Python35\\python.exe"
                        )
                        if $toxenv == py36 (
                            @set PYTHON="C:\\Python36\\python.exe"
                        )

                        @set py35orabove=true

                        if not $toxenv == py35 (
                            if not $toxenv == py36 (
                                @set py35orabove=false
                            )
                        )

                        if "%py35orabove%" == "true" (
                            if $label == windows (
                                @set INCLUDE="C:\\OpenSSL-Win32-2015\\include";%INCLUDE%
                                @set LIB="C:\\OpenSSL-Win32-2015\\lib";%LIB%
                            ) else (
                                @set INCLUDE="C:\\OpenSSL-Win64-2015\\include";%INCLUDE%
                                @set LIB="C:\\OpenSSL-Win64-2015\\lib";%LIB%
                            )
                        ) else (
                            if $label == windows (
                                @set INCLUDE="C:\\OpenSSL-Win32-2010\\include";%INCLUDE%
                                @set LIB="C:\\OpenSSL-Win32-2010\\lib";%LIB%
                            ) else (
                                @set INCLUDE="C:\\OpenSSL-Win64-2010\\include";%INCLUDE%
                                @set LIB="C:\\OpenSSL-Win64-2010\\lib";%LIB%
                            )
                        )

                        tox -r -e $toxenv
                        IF %ERRORLEVEL% NEQ 0 EXIT /B %ERRORLEVEL%
                        virtualenv .codecov
                        call .codecov/Scripts/activate
                        pip install codecov
                        codecov -e JOB_BASE_NAME
                    """
                } else if (label.contains("sierra")) {
                    ansiColor {
                        sh """#!/usr/bin/env bash
                            set -xe
                            # Jenkins logs in as a non-interactive shell, so we don't even have /usr/local/bin in PATH
                            export PATH=/usr/local/bin:\$PATH
                            # pyenv is nothing but trouble with non-interactive shells
                            #eval "\$(pyenv init -)"
                            export PATH="/Users/jenkins/.pyenv/shims:\${PATH}"
                            export PYENV_SHELL=bash
                            CRYPTOGRAPHY_OSX_NO_LINK_FLAGS=1 LDFLAGS="/usr/local/opt/openssl\\@1.1/lib/libcrypto.a /usr/local/opt/openssl\\@1.1/lib/libssl.a" CFLAGS="-I/usr/local/opt/openssl\\@1.1/include -Werror -Wno-error=deprecated-declarations -Wno-error=incompatible-pointer-types -Wno-error=unused-function -Wno-error=unused-command-line-argument" tox -r -e $toxenv --  --color=yes
                            # In a perfect world this would be a separate stage. This is not a perfect world.
                            virtualenv .venv
                            source .venv/bin/activate
                            pip install coverage
                            bash <(curl -s https://codecov.io/bash) -e JOB_BASE_NAME
                        """
                    }
                } else {
                    ansiColor {
                        sh """#!/usr/bin/env bash
                            set -xe
                            if [[ "$image_name" == *"libressl"* ]]; then
                                LD_LIBRARY_PATH="/usr/local/libressl/lib:\$LD_LIBRARY_PATH" LDFLAGS="-L/usr/local/libressl/lib" CFLAGS="-I/usr/local/libressl/include" tox -r -e $toxenv -- --color=yes
                            else
                                CFLAGS="" tox -vv -r -e $toxenv -- --color=yes
                            fi
                            # In a perfect world this would be a separate stage. This is not a perfect world.
                            virtualenv .venv
                            source .venv/bin/activate
                            pip install coverage
                            bash <(curl -s https://codecov.io/bash) -e JOB_BASE_NAME
                        """
                    }
                }
            }
        }
    } finally {
        deleteDir()
    }

}

def builders = [:]
for (config in configs) {
    def label = config["label"]
    def toxenvs = config["toxenvs"]

    for (_toxenv in toxenvs) {
        def toxenv = _toxenv

        if (label.contains("docker")) {
            def image_name = config["image_name"]
            def combinedName = "${image_name}-${toxenv}"
            builders[combinedName] = {
                node(label) {
                    stage(combinedName) {
                        docker.image(image_name).inside {
                            checkout_git()
                            build(toxenv, label, image_name)
                        }
                    }
                }
            }
        } else {
            def combinedName = "${label}-${toxenv}"
            builders[combinedName] = {
                node(label) {
                    stage(combinedName) {
                        build(toxenv, label, '')
                    }
                }
            }
        }
    }
}

parallel builders
