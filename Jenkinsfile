if (env.BRANCH_NAME == "master") {
    properties([pipelineTriggers([cron('@daily')])])
}

def configs = [
    [
        label: 'windows',
        toxenvs: ['py27', 'py34', 'py35', 'py36', 'py37'],
    ],
    [
        label: 'windows64',
        toxenvs: ['py27', 'py34', 'py35', 'py36', 'py37'],
    ],
    [
        label: 'sierra',
        toxenvs: ['py27', 'py36'],
    ],
    [
        label: 'yosemite',
        toxenvs: ['py27'],
    ],
    [
        label: 'docker',
        imageName: 'pyca/cryptography-runner-centos7',
        toxenvs: ['py27'],
    ],
    [
        label: 'docker',
        imageName: 'pyca/cryptography-runner-wheezy',
        toxenvs: ['py27'],
    ],
    [
        label: 'docker',
        imageName: 'pyca/cryptography-runner-jessie',
        toxenvs: ['py27', 'py34'],
    ],
    [
        label: 'docker',
        imageName: 'pyca/cryptography-runner-stretch',
        toxenvs: ['py27', 'py35'],
    ],
    [
        label: 'docker',
        imageName: 'pyca/cryptography-runner-buster',
        toxenvs: ['py27', 'py36'],
    ],
    [
        label: 'docker',
        imageName: 'pyca/cryptography-runner-sid',
        toxenvs: ['py27', 'py36'],
    ],
    [
        label: 'docker',
        imageName: 'pyca/cryptography-runner-ubuntu-xenial',
        toxenvs: ['py27', 'py35'],
    ],
    [
        label: 'docker',
        imageName: 'pyca/cryptography-runner-ubuntu-rolling',
        toxenvs: ['py27', 'py36', 'randomorder'],
    ],
    [
        label: 'docker',
        imageName: 'pyca/cryptography-runner-sid',
        toxenvs: ['docs'],
        artifacts: 'cryptography/docs/_build/html/**',
        artifactExcludes: '**/*.doctree',
    ],
    [
        label: 'docker',
        imageName: 'pyca/cryptography-runner-fedora',
        toxenvs: ['py27', 'py36'],
    ],
    [
        label: 'docker',
        imageName: 'pyca/cryptography-runner-alpine:latest',
        toxenvs: ['py36'],
    ],
]

/* Add the linkcheck job to our config list if we're on master */
if (env.BRANCH_NAME == "master") {
    configs.add(
        [
            label: 'docker',
            imageName: 'pyca/cryptography-runner-buster',
            toxenvs: ['docs-linkcheck'],
        ]
    )
}

def checkout_git(label) {
    retry(3) {
        def script = ""
        if (env.BRANCH_NAME.startsWith('PR-')) {
            script = """
            git clone --depth=1 https://github.com/pyca/cryptography
            cd cryptography
            git fetch origin +refs/pull/${env.CHANGE_ID}/merge:
            git checkout -qf FETCH_HEAD
            """
            if (label.contains("windows")) {
                bat script
            } else {
                sh """#!/bin/sh
                    set -xe
                    ${script}
                """
            }
        } else {
            checkout([
                $class: 'GitSCM',
                branches: [[name: "*/${env.BRANCH_NAME}"]],
                doGenerateSubmoduleConfigurations: false,
                extensions: [[
                    $class: 'RelativeTargetDirectory',
                    relativeTargetDir: 'cryptography'
                ]],
                submoduleCfg: [],
                userRemoteConfigs: [[
                    'url': 'https://github.com/pyca/cryptography'
                ]]
            ])
        }
    }
    if (label.contains("windows")) {
        bat """
            cd cryptography
            git rev-parse HEAD
        """
    } else {
        sh """
            cd cryptography
            git rev-parse HEAD
        """
    }
}
def build(toxenv, label, imageName, artifacts, artifactExcludes) {
    try {
        timeout(time: 30, unit: 'MINUTES') {

            checkout_git(label)
            checkout([
                $class: 'GitSCM',
                extensions: [[
                    $class: 'RelativeTargetDirectory',
                    relativeTargetDir: 'wycheproof',
                ]],
                userRemoteConfigs: [[
                    'url': 'https://github.com/google/wycheproof',
                ]]
            ])

            withCredentials([string(credentialsId: 'cryptography-codecov-token', variable: 'CODECOV_TOKEN')]) {
                withEnv(["LABEL=$label", "TOXENV=$toxenv", "IMAGE_NAME=$imageName"]) {
                    if (label.contains("windows")) {
                        def pythonPath = [
                            py27: "C:\\Python27\\python.exe",
                            py34: "C:\\Python34\\python.exe",
                            py35: "C:\\Python35\\python.exe",
                            py36: "C:\\Python36\\python.exe",
                            py37: "C:\\Python37\\python.exe"
                        ]
                        if (toxenv == "py35" || toxenv == "py36" || toxenv == "py37") {
                            opensslPaths = [
                                "windows": [
                                    "include": "C:\\OpenSSL-Win32-2015\\include",
                                    "lib": "C:\\OpenSSL-Win32-2015\\lib"
                                ],
                                "windows64": [
                                    "include": "C:\\OpenSSL-Win64-2015\\include",
                                    "lib": "C:\\OpenSSL-Win64-2015\\lib"
                                ]
                            ]
                        } else {
                            opensslPaths = [
                                "windows": [
                                    "include": "C:\\OpenSSL-Win32-2010\\include",
                                    "lib": "C:\\OpenSSL-Win32-2010\\lib"
                                ],
                                "windows64": [
                                    "include": "C:\\OpenSSL-Win64-2010\\include",
                                    "lib": "C:\\OpenSSL-Win64-2010\\lib"
                                ]
                            ]
                        }
                        bat """
                            cd cryptography
                            @set PATH="C:\\Python27";"C:\\Python27\\Scripts";%PATH%
                            @set PYTHON="${pythonPath[toxenv]}"

                            @set INCLUDE="${opensslPaths[label]['include']}";%INCLUDE%
                            @set LIB="${opensslPaths[label]['lib']}";%LIB%
                            tox -r -- --wycheproof-root=../wycheproof
                            IF %ERRORLEVEL% NEQ 0 EXIT /B %ERRORLEVEL%
                            virtualenv .codecov
                            call .codecov/Scripts/activate
                            REM this pin must be kept in sync with tox.ini
                            pip install coverage
                            pip install codecov
                            codecov -e JOB_BASE_NAME,LABEL,TOXENV
                        """
                    } else if (label.contains("sierra") || label.contains("yosemite")) {
                        ansiColor {
                            sh """#!/usr/bin/env bash
                                set -xe
                                # Jenkins logs in as a non-interactive shell, so we don't even have /usr/local/bin in PATH
                                export PATH="/usr/local/bin:\${PATH}"
                                export PATH="/Users/jenkins/.pyenv/shims:\${PATH}"
                                cd cryptography
                                CRYPTOGRAPHY_SUPPRESS_LINK_FLAGS=1 \
                                    LDFLAGS="/usr/local/opt/openssl\\@1.1/lib/libcrypto.a /usr/local/opt/openssl\\@1.1/lib/libssl.a" \
                                    CFLAGS="-I/usr/local/opt/openssl\\@1.1/include -Werror -Wno-error=deprecated-declarations -Wno-error=incompatible-pointer-types-discards-qualifiers -Wno-error=unused-function -Wno-error=unused-command-line-argument -mmacosx-version-min=10.9" \
                                    tox -r --  --color=yes --wycheproof-root=../wycheproof
                                virtualenv .venv
                                source .venv/bin/activate
                                # This pin must be kept in sync with tox.ini
                                pip install coverage
                                bash <(curl -s https://codecov.io/bash) -e JOB_BASE_NAME,LABEL,TOXENV
                            """
                        }
                    } else {
                        ansiColor {
                            sh """#!/usr/bin/env bash
                                set -xe
                                cd cryptography
                                tox -r -- --color=yes --wycheproof-root=../wycheproof
                                virtualenv .venv
                                source .venv/bin/activate
                                # This pin must be kept in sync with tox.ini
                                pip install coverage
                                bash <(curl -s https://codecov.io/bash) -e JOB_BASE_NAME,LABEL,TOXENV,IMAGE_NAME
                            """
                        }
                        if (artifacts) {
                            archiveArtifacts artifacts: artifacts, excludes: artifactExcludes
                        }
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
    def artifacts = config["artifacts"]
    def artifactExcludes = config["artifactExcludes"]

    for (_toxenv in toxenvs) {
        def toxenv = _toxenv

        if (label.contains("docker")) {
            def imageName = config["imageName"]
            def combinedName = "${imageName}-${toxenv}"
            builders[combinedName] = {
                node(label) {
                    stage(combinedName) {
                        def buildImage = docker.image(imageName)
                        buildImage.pull()
                        buildImage.inside {
                            build(toxenv, label, imageName, artifacts, artifactExcludes)
                        }
                    }
                }
            }
        } else {
            def combinedName = "${label}-${toxenv}"
            builders[combinedName] = {
                node(label) {
                    stage(combinedName) {
                        build(toxenv, label, '', null, null)
                    }
                }
            }
        }
    }
}

/* Add the python setup.py test builder */
builders["setup.py-test"] = {
    node("docker") {
        stage("python setup.py test") {
            docker.image("pyca/cryptography-runner-ubuntu-rolling").inside {
                try {
                    checkout_git("docker")
                    sh """#!/usr/bin/env bash
                        set -xe
                        cd cryptography
                        virtualenv .venv
                        source .venv/bin/activate
                        python setup.py test
                    """
                } finally {
                    deleteDir()
                }

            }
        }
    }
}

parallel builders
