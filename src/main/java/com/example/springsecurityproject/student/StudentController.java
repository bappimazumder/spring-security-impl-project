package com.example.springsecurityproject.student;

import org.springframework.web.bind.annotation.*;
import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("api/v1/students")
public class StudentController {

    private static final List<Student> STUDENT_LIST = Arrays.asList(
            new Student(1,"Bappi Mazumder"),
            new Student(2,"Maria Bond"),
            new Student(3,"David Balame")
    );

    @GetMapping(path = "/{studentId}")
    public Student getStudent(@PathVariable("studentId") Integer studentId ){
         return STUDENT_LIST.stream()
        .filter(student -> studentId.equals(student.getStudentId())).
                findFirst().orElseThrow(()-> new IllegalArgumentException("student" + studentId));
    }


}
