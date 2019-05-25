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
]

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
    bat """
        cd cryptography
        git rev-parse HEAD
    """
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

parallel builders
