pipeline {
    agent any
    stages {
        stage('Git Checkout') {
            steps {
                checkout([$class: 'GitSCM', branches: [[name: '*/master']], userRemoteConfigs: [[url: 'https://github.com/stwins60/s3-browser.git']]])
            }
        }
        stage('Docker Build') {
            steps {
                script {
                    sh "docker build -t idrisniyi94/s3-browser ."
                }
            }
        }
        stage('Docker Push') {
            steps {
                script {
                    withCredentials([string(credentialsId: '8118938e-2088-4712-82e0-5dd7b7e6e5fc', variable: 'DOCKERHUB')]) {
                        sh "docker login -u idrisniyi94 -p $DOCKERHUB"
                        sh "docker push idrisniyi94/s3-browser"
                    }
                }
            }
        }
    }
}