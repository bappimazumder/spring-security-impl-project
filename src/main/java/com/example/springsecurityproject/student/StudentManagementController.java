package com.example.springsecurityproject.student;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("management/api/v1/students")

public class StudentManagementController {
    private static final List<Student> STUDENT_LIST = Arrays.asList(
        new Student(1,"Bappi Mazumder"),
        new Student(2,"Maria Bond"),
        new Student(3,"David Balame")
    );

    @GetMapping
    @PreAuthorize("hasAnyRole('ROLE_ADMIN,ROLE_ADMINTRANEE')")
    public static List<Student> getStudentList() {
        return STUDENT_LIST;
    }

    @PostMapping
    @PreAuthorize("hasAnyAuthority('student:write')")
    public void registerNewStudent(@RequestBody Student student){
        System.out.println("New student register");
        System.out.println(student);
    }

    @DeleteMapping(path = "{studentId}")
    public void deleteStudent(@PathVariable("studentId") Integer studentId){
        System.out.println("Delete student");
        System.out.println(studentId);
    }
    @PutMapping(path = "{studentId}")
    public void updateStudent(@PathVariable("studentId") Integer studentId, @RequestBody Student student){
        System.out.println("Update student");
        System.out.println(String.format("%s %s",student,student));
    }
}