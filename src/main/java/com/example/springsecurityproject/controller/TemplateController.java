package com.example.springsecurityproject.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

@RestController
@RequestMapping("/")
public class TemplateController {
    @GetMapping("login")
    public ModelAndView getLogin(){
        ModelAndView modelAndView = new ModelAndView();
        modelAndView.setViewName("login");
        return modelAndView;
    }
    @GetMapping("courses")
    public ModelAndView getCourses(){
        ModelAndView modelAndView = new ModelAndView();
        modelAndView.setViewName("course_list");
        return modelAndView;
    }
}
