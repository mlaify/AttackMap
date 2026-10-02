package com.example.rules;

import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class RuleController {

    private final ExpressionParser parser = new SpelExpressionParser();

    @GetMapping("/rules/eval")
    public Object evaluate(@RequestParam("qty") int qty) { // taint: route
        StandardEvaluationContext ctx = new StandardEvaluationContext();
        ctx.setVariable("qty", qty);
        return parser.parseExpression("#qty * 9.99").getValue(ctx); // taint: sink
    }
}
