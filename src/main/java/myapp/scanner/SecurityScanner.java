package myapp.scanner;

import myapp.model.SecurityFinding;

import java.util.List;

public interface SecurityScanner {

    List<SecurityFinding> scan(String region);
}