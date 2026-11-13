pipeline {

    agent any


    environment {

        KUBECONFIG = 'C:/ProgramData/Jenkins/.jenkins/kube/config'

        KUBE_NAMESPACE = 'webshield'

        API_IMAGE = 'webshield-api'
        WORKER_IMAGE = 'webshield-worker'
        WEB_IMAGE = 'webshield-web'
        LAB_IMAGE = 'webshield-lab'
    }


    options {

        disableConcurrentBuilds()

        buildDiscarder(
            logRotator(
                numToKeepStr: '10'
            )
        )

        timeout(
            time: 45,
            unit: 'MINUTES'
        )
    }


    stages {


        // ==================================================
        // Checkout
        // ==================================================

        stage('Checkout Source') {

            steps {

                echo 'Checking out WebShield source code...'

                checkout scm

                bat 'git status'

                bat 'git log -1 --oneline'
            }
        }


        // ==================================================
        // Environment
        // ==================================================

        stage('Validate Environment') {

            steps {

                bat 'node --version'

                bat 'npm --version'

                bat 'git --version'

                bat 'docker --version'

                bat 'kubectl version --client'

                bat 'kubectl config current-context'

                bat 'kubectl get nodes'
            }
        }


        // ==================================================
        // Dependencies
        // ==================================================

        stage('Install Server Dependencies') {

            steps {

                bat '''
                if exist server\\package-lock.json (
                    cd server
                    npm ci
                ) else (
                    cd server
                    npm install
                )
                '''
            }
        }


        stage('Install Client Dependencies') {

            steps {

                bat '''
                if exist client\\package-lock.json (
                    cd client
                    npm ci
                ) else (
                    cd client
                    npm install
                )
                '''
            }
        }


        // ==================================================
        // Source Validation
        // ==================================================

        stage('Validate Source') {

            steps {

                bat 'node --check server/src/index.js'

                bat 'node --check server/src/worker.js'

                bat 'node --check server/src/scanner.js'

                bat 'node --check server/src/playwrightCrawler.js'

                bat 'node --check server/src/report.js'

                bat 'node --check server/src/db.js'

                bat 'node --check server/src/security.js'

                bat 'node --check lab/index.js'
            }
        }


        // ==================================================
        // Unit Tests
        // ==================================================

        stage('Unit Tests') {

            steps {

                bat '''
                node --test tests/security.unit.test.mjs
                '''
            }
        }


        // ==================================================
        // React Build
        // ==================================================

        stage('Frontend Build') {

            steps {

                bat '''
                cd client
                npm run build
                '''
            }
        }


        // ==================================================
        // Docker Images
        // ==================================================

        stage('Build Docker Images') {

            steps {

                bat '''
                docker build ^
                  -t %API_IMAGE%:%BUILD_NUMBER% ^
                  -t %API_IMAGE%:local ^
                  ./server
                '''


                bat '''
                docker build ^
                  -f server/Dockerfile.worker ^
                  -t %WORKER_IMAGE%:%BUILD_NUMBER% ^
                  -t %WORKER_IMAGE%:local ^
                  ./server
                '''


                bat '''
                docker build ^
                  -t %LAB_IMAGE%:%BUILD_NUMBER% ^
                  -t %LAB_IMAGE%:local ^
                  ./lab
                '''


                bat '''
                docker build ^
                  -t %WEB_IMAGE%:%BUILD_NUMBER% ^
                  -t %WEB_IMAGE%:local ^
                  ./client
                '''
            }
        }


        // ==================================================
        // Verify Images
        // ==================================================

        stage('Verify Docker Images') {

            steps {

                bat 'docker image inspect %API_IMAGE%:%BUILD_NUMBER%'

                bat 'docker image inspect %WORKER_IMAGE%:%BUILD_NUMBER%'

                bat 'docker image inspect %LAB_IMAGE%:%BUILD_NUMBER%'

                bat 'docker image inspect %WEB_IMAGE%:%BUILD_NUMBER%'
            }
        }


        // ==================================================
        // Kubernetes Manifests
        // ==================================================

        stage('Apply Kubernetes Configuration') {

            steps {

                bat 'kubectl apply -f k8s/00-namespace-config.yaml'

                bat 'kubectl apply -f k8s/01-infrastructure.yaml'

                bat 'kubectl apply -f k8s/02-api-worker.yaml'

                bat 'kubectl apply -f k8s/03-web.yaml'
            }
        }


        // ==================================================
        // Release
        // ==================================================

        stage('Deploy Release') {

            steps {

                bat '''
                kubectl set image ^
                  deployment/api ^
                  api=%API_IMAGE%:%BUILD_NUMBER% ^
                  -n %KUBE_NAMESPACE%
                '''


                bat '''
                kubectl set image ^
                  deployment/worker ^
                  worker=%WORKER_IMAGE%:%BUILD_NUMBER% ^
                  -n %KUBE_NAMESPACE%
                '''


                bat '''
                kubectl set image ^
                  deployment/lab ^
                  lab=%LAB_IMAGE%:%BUILD_NUMBER% ^
                  -n %KUBE_NAMESPACE%
                '''


                bat '''
                kubectl set image ^
                  deployment/web ^
                  web=%WEB_IMAGE%:%BUILD_NUMBER% ^
                  -n %KUBE_NAMESPACE%
                '''
            }
        }


        // ==================================================
        // Rollout
        // ==================================================

        stage('Verify Kubernetes Rollout') {

            steps {

                bat '''
                kubectl rollout status ^
                  deployment/api ^
                  -n %KUBE_NAMESPACE% ^
                  --timeout=180s
                '''


                bat '''
                kubectl rollout status ^
                  deployment/worker ^
                  -n %KUBE_NAMESPACE% ^
                  --timeout=240s
                '''


                bat '''
                kubectl rollout status ^
                  deployment/lab ^
                  -n %KUBE_NAMESPACE% ^
                  --timeout=180s
                '''


                bat '''
                kubectl rollout status ^
                  deployment/web ^
                  -n %KUBE_NAMESPACE% ^
                  --timeout=180s
                '''
            }
        }


        // ==================================================
        // API Smoke Test
        // ==================================================

        stage('API Smoke Test') {

            steps {

                bat '''
                kubectl exec ^
                  deployment/api ^
                  -n %KUBE_NAMESPACE% ^
                  -- node -e "fetch('http://127.0.0.1:5000/api/health').then(function(r){if(!r.ok){process.exit(1)};return r.text()}).then(function(t){console.log(t)}).catch(function(e){console.error(e);process.exit(1)})"
                '''
            }
        }


        // ==================================================
        // FULL INTEGRATION TEST
        // ==================================================

        stage('Full Integration Test') {

            steps {

                echo 'Running complete WebShield Kubernetes integration test...'


                bat '''
                powershell ^
                  -NoProfile ^
                  -ExecutionPolicy Bypass ^
                  -File tests\\run-k8s-integration.ps1
                '''
            }
        }


        // ==================================================
        // Deployment Summary
        // ==================================================

        stage('Deployment Summary') {

            steps {

                bat '''
                kubectl get pods ^
                  -n %KUBE_NAMESPACE% ^
                  -o wide
                '''


                bat '''
                kubectl get services ^
                  -n %KUBE_NAMESPACE%
                '''


                bat '''
                kubectl get pvc ^
                  -n %KUBE_NAMESPACE%
                '''


                bat '''
                kubectl get deployments ^
                  -n %KUBE_NAMESPACE%
                '''
            }
        }
    }


    // ==================================================
    // Post
    // ==================================================

    post {

        success {

            echo '=========================================='
            echo 'WEBSHIELD CI/CD PIPELINE SUCCESSFUL'
            echo "Build Number: ${BUILD_NUMBER}"
            echo 'Unit Tests: PASSED'
            echo 'Frontend Build: PASSED'
            echo 'Docker Images: BUILT'
            echo 'Kubernetes Deployment: SUCCESSFUL'
            echo 'API Smoke Test: PASSED'
            echo 'Full Integration Test: PASSED'
            echo '=========================================='
        }


        failure {

            echo '=========================================='
            echo 'WEBSHIELD CI/CD PIPELINE FAILED'
            echo "Build Number: ${BUILD_NUMBER}"
            echo 'Check the failed stage above.'
            echo '=========================================='


            bat '''
            kubectl get pods ^
              -n %KUBE_NAMESPACE% ^
              -o wide
            '''


            bat '''
            kubectl get events ^
              -n %KUBE_NAMESPACE% ^
              --sort-by=.lastTimestamp
            '''
        }


        always {

            echo "WebShield Jenkins build ${BUILD_NUMBER} finished."
        }
    }
}