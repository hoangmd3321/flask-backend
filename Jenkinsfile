pipeline {
    agent any

    stages {

        stage('Down Current Container') {
            steps {
                sh 'sudo docker-compose down'
            }
        }

        stage('Build') {
            steps {
                sh 'sudo docker-compose build'
            }
        }

        stage('Deploy') {
            steps {
                sh 'sudo docker-compose up -d'
            }
        }
    }
}