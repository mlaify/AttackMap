package com.example.directory;

import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import org.springframework.ldap.support.LdapEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DirectoryController {

    private final DirContext ctx;

    public DirectoryController(DirContext ctx) {
        this.ctx = ctx;
    }

    @GetMapping("/directory/lookup")
    public boolean exists(@RequestParam("uid") String uid) throws NamingException { // taint: route
        String filter = "(uid=" + LdapEncoder.filterEncode(uid) + ")";
        return ctx.search("ou=people,dc=example,dc=com", filter, new SearchControls()).hasMore(); // taint: sink
    }
}
