package com.example.rules;

import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class RuleController {

    private final ExpressionParser parser = new SpelExpressionParser();

    @GetMapping("/rules/eval")
    public Object evaluate(@RequestParam("rule") String rule) { // taint: route
        String expression = rule.trim();
        return parser.parseExpression(expression).getValue(); // taint: sink
    }
}
