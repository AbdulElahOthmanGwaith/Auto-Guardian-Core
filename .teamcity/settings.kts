import jetbrains.buildServer.configs.kotlin.v2019_2.*
import jetbrains.buildServer.configs.kotlin.v2019_2.buildSteps.python
import jetbrains.buildServer.configs.kotlin.v2019_2.triggers.vcs

version = "2021.1"

project {
    id("AutoGuardianCore")
    name = "Auto Guardian Core"
    description = "نظام متكامل لفحص الكود البرمجي واكتشاف الثغرات الأمنية"

    buildType(BuildTests)
    buildType(BuildProduction)
    buildType(DeployProduction)

    params {
        param("github.owner", "AbdulElahOthmanGwaith")
        param("github.repo", "Auto-Guardian-Core")
        param("docker.registry", "docker.io")
    }
}

object BuildTests : BuildType({
    id("BuildTests")
    name = "Build & Test"
    description = "بناء واختبار المشروع"

    vcs {
        root(DslContext.settingsRoot)
    }

    steps {
        python {
            name = "Install Dependencies"
            command = "install"
            args = "-r requirements.txt"
        }
        python {
            name = "Run Tests"
            command = "script"
            scriptContent = """
                python verify.py
                python verify_extras.py
            """.trimIndent()
        }
        python {
            name = "Run Security Scan"
            command = "script"
            scriptContent = """
                python scripts/enhanced_security_scanner.py
            """.trimIndent()
        }
    }

    triggers {
        vcs {
            branchFilter = "+:*"
        }
    }

    failureConditions {
        executionTimeoutMin = 60
    }
})

object BuildProduction : BuildType({
    id("BuildProduction")
    name = "Build Docker Image"
    description = "بناء صورة Docker للإنتاج"

    vcs {
        root(DslContext.settingsRoot)
    }

    steps {
        exec {
            name = "Build Docker Image"
            command = """
                docker build -f Dockerfile.api -t auto-guardian-core:latest .
                docker tag auto-guardian-core:latest docker.io/abdulelaothman/auto-guardian-core:latest
            """.trimIndent()
        }
    }

    dependencies {
        dependency(BuildTests) {
            snapshot {
                onDependencyFailure = FailureAction.FAIL_TO_START
            }
        }
    }

    triggers {
        vcs {
            branchFilter = "+:main"
        }
    }
})

object DeployProduction : BuildType({
    id("DeployProduction")
    name = "Deploy to Production"
    description = "نشر إلى الإنتاج"

    vcs {
        root(DslContext.settingsRoot)
    }

    steps {
        exec {
            name = "Push Docker Image"
            command = """
                docker push docker.io/abdulelaothman/auto-guardian-core:latest
            """.trimIndent()
        }
        exec {
            name = "Deploy Services"
            command = """
                docker-compose -f docker-compose.production.yml up -d
            """.trimIndent()
        }
    }

    dependencies {
        dependency(BuildProduction) {
            snapshot {
                onDependencyFailure = FailureAction.FAIL_TO_START
            }
        }
    }

    triggers {
        vcs {
            branchFilter = "+:main"
        }
    }
})
