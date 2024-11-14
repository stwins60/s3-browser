pipeline {
    agent any
    environment {
        DOCKERHUB_CREDENTIALS = credentials('8118938e-2088-4712-82e0-5dd7b7e6e5fc')
        IMAGE_TAG = "v.0.0.${env.BUILD_NUMBER}-stable"
        IMAGE_NAME = "idrisniyi94/s3-browser:${IMAGE_TAG}"
        
    }
    stages {
        // stage('Git Checkout') {
        //     steps {
        //         checkout([$class: 'GitSCM', branches: [[name: '*/master']], userRemoteConfigs: [[url: 'https://github.com/stwins60/s3-browser.git']]])
        //     }
        // }
        stage('Docker Build') {
            steps {
                script {
                    sh "docker build -t $IMAGE_NAME ."
                }
            }
        }
        stage('Docker Push') {
            steps {
                script {
                    sh "echo ${DOCKERHUB_CREDENTIALS_PSW} | docker login -u ${DOCKERHUB_CREDENTIALS_USR} --password-stdin"
                    sh "docker push $IMAGE_NAME"
                }
            }
        }
    }
}