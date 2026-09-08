package myapp;

import org.springframework.stereotype.Component;
import picocli.CommandLine.Command;

@Component
@Command(
    name = "cloudsentry",
    description = "CloudSentry security CLI",
    mixinStandardHelpOptions = true
)
public class CloudSentryCommand implements Runnable {

    @Override
    public void run() {
        System.out.println("CloudSentry CLI");
        System.out.println("Use: cloudsentry scan");
    }
}