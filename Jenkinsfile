node('docker') {

  stage('build') {
    checkout scm

    sh 'rm -Rf build; mkdir -p build'

    def buildImage = docker.build("dcos-oauth-build:${env.BUILD_TAG}", '-f JenkinsDockerfile .')
    buildImage.inside {
      sh 'ln -s $PWD /go/src/github.com/dcos/dcos-oauth'
      sh 'cd /go/src/github.com/dcos/dcos-oauth; make test && make install'
      sh 'cp /go/bin/dcos-oauth ./build/dcos-oauth'
    }

    archiveArtifacts 'build/dcos-oauth'
  }

  stage('upload') {
    def awsCli = docker.image('mesosphere/aws-cli')
    awsCli.pull()
    withCredentials([
        [
            $class: 'StringBinding',
            credentialsId: "dcos-oauth-deployment-aws-access-key-id",
            variable: 'AWS_ACCESS_KEY_ID'
        ],
        [
            $class: 'StringBinding',
            credentialsId: "dcos-oauth-deployment-aws-secret-access-key",
            variable: 'AWS_SECRET_ACCESS_KEY'
        ]
    ]) {
        awsCli.inside(
            "-e AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY"
        ) {
            sh 'aws s3 cp build/dcos-oauth s3://ethos-utils/dcos/bin/dcos-oauth'
        }
    }
  }
}
