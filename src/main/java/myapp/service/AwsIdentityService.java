package myapp.service;

import org.springframework.stereotype.Service;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.model.GetCallerIdentityResponse;

@Service
public class AwsIdentityService {

    public boolean checkIdentity() {

        try (StsClient stsClient = StsClient.create()) {

            GetCallerIdentityResponse identity =
                    stsClient.getCallerIdentity();

            System.out.println("AWS connection successful.");
            System.out.println("AWS Account: " + identity.account());
            System.out.println("AWS ARN: " + identity.arn());

            return true;

        } catch (Exception e) {

            System.out.println("AWS connection failed.");

            String message = e.getMessage();

            if (message == null || message.isBlank()) {
                message = "Unable to authenticate with AWS credentials.";
            }

            System.out.println("Reason: " + message);

            return false;
        }
    }
}