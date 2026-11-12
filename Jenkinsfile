pipeline {

    agent any


    // ==================================================
    // Global Environment
    // ==================================================

    environment {

        KUBECONFIG = 'C:/ProgramData/Jenkins/.jenkins/kube/config'

        KUBE_NAMESPACE = 'webshield'

        API_IMAGE = 'webshield-api'
        WORKER_IMAGE = 'webshield-worker'
        WEB_IMAGE = 'webshield-web'
        LAB_IMAGE = 'webshield-lab'
    }


    // ==================================================
    // Pipeline Options
    // ==================================================

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


        // ==============================================
        // Checkout
        // ==============================================

        stage('Checkout Source') {

            steps {

                echo 'Checking out WebShield source code...'

                checkout scm

                bat 'git status'

                bat 'git log -1 --oneline'
            }
        }


        // ==============================================
        // Environment Validation
        // ==============================================

        stage('Validate Environment') {

            steps {

                echo 'Checking Jenkins build environment...'

                bat 'node --version'

                bat 'npm --version'

                bat 'git --version'

                bat 'docker --version'

                bat 'kubectl version --client'

                bat 'kubectl config current-context'

                bat 'kubectl get nodes'
            }
        }


        // ==============================================
        // Install Server Dependencies
        // ==============================================

        stage('Install Server Dependencies') {

            steps {

                echo 'Installing backend dependencies...'

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


        // ==============================================
        // Install Client Dependencies
        // ==============================================

        stage('Install Client Dependencies') {

            steps {

                echo 'Installing frontend dependencies...'

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


        // ==============================================
        // Source Validation
        // ==============================================

        stage('Validate Source') {

            steps {

                echo 'Validating WebShield Node.js source files...'

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


        // ==============================================
        // Unit Tests
        // ==============================================

        stage('Unit Tests') {

            steps {

                echo 'Running WebShield security unit tests...'

                bat '''
                node --test tests/security.unit.test.mjs
                '''
            }
        }


        // ==============================================
        // Frontend Build
        // ==============================================

        stage('Frontend Build') {

            steps {

                echo 'Building React frontend...'

                bat '''
                cd client
                npm run build
                '''
            }
        }


        // ==============================================
        // Docker Build
        // ==============================================

        stage('Build Docker Images') {

            steps {

                echo "Building WebShield Docker images for build ${BUILD_NUMBER}..."


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


        // ==============================================
        // Docker Image Verification
        // ==============================================

        stage('Verify Docker Images') {

            steps {

                echo 'Verifying generated Docker images...'


                bat '''
                docker image inspect %API_IMAGE%:%BUILD_NUMBER%
                '''


                bat '''
                docker image inspect %WORKER_IMAGE%:%BUILD_NUMBER%
                '''


                bat '''
                docker image inspect %LAB_IMAGE%:%BUILD_NUMBER%
                '''


                bat '''
                docker image inspect %WEB_IMAGE%:%BUILD_NUMBER%
                '''
            }
        }


        // ==============================================
        // Kubernetes Configuration
        // ==============================================

        stage('Apply Kubernetes Configuration') {

            steps {

                echo 'Applying Kubernetes manifests...'


                bat '''
                kubectl apply ^
                  -f k8s/00-namespace-config.yaml
                '''


                bat '''
                kubectl apply ^
                  -f k8s/01-infrastructure.yaml
                '''


                bat '''
                kubectl apply ^
                  -f k8s/02-api-worker.yaml
                '''


                bat '''
                kubectl apply ^
                  -f k8s/03-web.yaml
                '''
            }
        }


        // ==============================================
        // Kubernetes Release
        // ==============================================

        stage('Deploy Release') {

            steps {

                echo "Deploying WebShield build ${BUILD_NUMBER}..."


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


        // ==============================================
        // Rollout Verification
        // ==============================================

        stage('Verify Kubernetes Rollout') {

            steps {

                echo 'Waiting for Kubernetes deployments...'


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


        // ==============================================
        // API Smoke Test
        // ==============================================

        stage('API Smoke Test') {

            steps {

                echo 'Checking deployed WebShield API health...'


                bat '''
                kubectl exec ^
                  deployment/api ^
                  -n %KUBE_NAMESPACE% ^
                  -- node -e "fetch('http://127.0.0.1:5000/api/health').then(function(r){if(!r.ok){process.exit(1)};return r.text()}).then(function(t){console.log(t)}).catch(function(e){console.error(e);process.exit(1)})"
                '''
            }
        }


        // ==============================================
        // Final Kubernetes Verification
        // ==============================================

        stage('Deployment Summary') {

            steps {

                echo 'WebShield deployment summary:'


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
    // Post Actions
    // ==================================================

    post {

        success {

            echo '=========================================='
            echo 'WEBShield CI/CD PIPELINE SUCCESSFUL'
            echo "Build Number: ${BUILD_NUMBER}"
            echo 'Tests: PASSED'
            echo 'Docker Images: BUILT'
            echo 'Kubernetes Deployment: SUCCESSFUL'
            echo 'API Health Check: PASSED'
            echo '=========================================='
        }


        failure {

            echo '=========================================='
            echo 'WEBShield CI/CD PIPELINE FAILED'
            echo "Build Number: ${BUILD_NUMBER}"
            echo 'Check the failed pipeline stage above.'
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