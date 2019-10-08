module Garrison
  module Checks
    class CheckPublicAccessBlock < Check

      def settings
        self.source ||= 'aws-s3'
        self.severity ||= 'critical'
        self.family ||= 'infrastructure'
        self.type ||= 'compliance'
        self.options[:regions] ||= 'all'
      end

      def key_values
        [
          { key: 'datacenter', value: 'aws' },
          { key: 'aws-service', value: 's3' },
          { key: 'aws-account', value: AwsHelper.whoami }
        ]
      end

      def perform
        options[:regions] = AwsHelper.all_regions if options[:regions] == 'all'
        options[:regions].each do |region|
          Logging.info "Checking region #{region}"
          buckets_without_public_block = public_block_s3(region)

          buckets_without_public_block.each do |instance|
            alert(
              name: 'Public Access Block Violation',
              target: instance,
              detail: 'bucket_public_access_blocked: false',
              finding: instance,
              finding_id: "aws-s3-#{instance}-public_access",
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
            ) unless options[:excluded_buckets].include? instance
          end
        end
      end

      private

      def public_block_s3(region)
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

        buckets_without_public_block = []

        s3.buckets.each do |bucket|
          if s3.client.get_bucket_location(bucket: bucket.name).location_constraint == region
            begin 
              s3.client.get_public_access_block(bucket: bucket.name)
            rescue => e
              buckets_without_public_block << bucket.name
            end
          end
        end

        buckets_without_public_block
      end
    end
  end
end
