module Garrison
  class AwsHelper

    def self.whoami
      @whoami ||= ENV['AWS_ACCOUNT_ID'] || Aws::STS::Client.new(region: 'us-east-1').get_caller_identity.account
    end

    def self.all_regions
      Aws::Partitions.partition('aws').service('S3').regions
    end

  end
end
