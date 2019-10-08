module Garrison
  module Checks
    class CheckEncryption < Check

      def settings
        self.source ||= 'aws-s3'
        self.severity ||= 'critical'
        self.family ||= 'infrastructure'
        self.type ||= 'compliance'
        self.options[:regions] ||= 'all'
        self.options[:engines] ||= 'all'
      end

      def key_values
        [
          { key: 'datacenter', value: 'aws' },
          { key: 'aws-service', value: 'rds' },
          { key: 'aws-account', value: AwsHelper.whoami }
        ]
      end

      def perform
        options[:regions] = AwsHelper.all_regions if options[:regions] == 'all'
        options[:regions].each do |region|
          Logging.info "Checking region #{region}"
          not_encrypted = unecrypted_s3(region)

          not_encrypted.each do |instance|
            alert(
              name: 'Encryption Violation',
              target: instance,
              detail: 'bucket_encrypted: false',
              finding: instance,
              finding_id: "aws-s3-#{instance}-encryption",
              urls: [
                {
                  name: 'AWS Dashboard',
                  url: "https://console.aws.amazon.com/s3/buckets/#{instance}?region=#{region}"
                }
              ],
              key_values: [
                {
                  key: 'aws-region',
                  value: region
                }
              ]
            )
          end
        end
      end

      private

      def unecrypted_s3(region)
        if ENV['AWS_ASSUME_ROLE_CREDENTIALS_ARN']
          role_credentials = Aws::AssumeRoleCredentials.new(
            client: Aws::STS::Client.new(region: region),
            role_arn: ENV['AWS_ASSUME_ROLE_CREDENTIALS_ARN'],
            role_session_name: 'garrison-agent-s3'
          )

          s3 = Aws::S3::Resource.new(credentials: role_credentials)
        else
          s3 = Aws::S3::Resource.new(region: region)
        end

        unencrypted_buckets = []

        s3.buckets.each do |bucket|
          if s3.client.get_bucket_location(bucket: bucket.name).location_constraint == region
            begin
              s3.client.get_bucket_encryption(bucket: bucket.name)
            rescue Aws::S3::Errors::ServerSideEncryptionConfigurationNotFoundError
              unencrypted_buckets << bucket.name
            end
          end
        end
        puts unencrypted_buckets.count
        unencrypted_buckets
      end
    end
  end
end
