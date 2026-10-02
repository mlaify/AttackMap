package com.example.catalog;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.w3c.dom.Document;

@RestController
public class CatalogController {

    private final Document catalog;

    public CatalogController(Document catalog) {
        this.catalog = catalog;
    }

    @GetMapping("/catalog/item")
    public String price(@RequestParam("sku") String sku) throws XPathExpressionException { // taint: route
        XPath xpath = XPathFactory.newInstance().newXPath();
        xpath.setXPathVariableResolver(name -> sku);
        return xpath.evaluate("//item[@sku=$sku]/price/text()", catalog); // taint: sink
    }
}
