package myapp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.WebApplicationType;
import org.springframework.context.ConfigurableApplicationContext;
import picocli.CommandLine;

@SpringBootApplication
public class MyappApplication {

    public static void main(String[] args) {

        SpringApplication app =
                new SpringApplication(MyappApplication.class);

        // CloudSentry is a CLI, not a web application
        app.setWebApplicationType(WebApplicationType.NONE);

        ConfigurableApplicationContext context =
                app.run();

        CloudSentryCommand rootCommand =
                context.getBean(CloudSentryCommand.class);

        ScanCommand scanCommand =
                context.getBean(ScanCommand.class);

        CommandLine commandLine =
                new CommandLine(rootCommand);

        commandLine.addSubcommand("scan", scanCommand);
        
        int exitCode =
                commandLine.execute(args);

        System.exit(exitCode);
    }
}