package myapp.config;

import org.springframework.stereotype.Component;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.ec2.Ec2Client;
import software.amazon.awssdk.services.iam.IamClient;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.sts.StsClient;

@Component
public class AwsClientFactory {

    public S3Client createS3Client(String region) {
        return S3Client.builder()
                .region(Region.of(region))
                .build();
    }

    public IamClient createIamClient(String region) {
        return IamClient.builder()
                .region(Region.of(region))
                .build();
    }

    public Ec2Client createEc2Client(String region) {
        return Ec2Client.builder()
                .region(Region.of(region))
                .build();
    }

    public StsClient createStsClient(String region) {
        return StsClient.builder()
                .region(Region.of(region))
                .build();
    }
}