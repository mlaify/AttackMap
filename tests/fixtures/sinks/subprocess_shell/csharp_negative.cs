using System.Collections.Generic;
using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace Diag.Controllers;

[ApiController]
public class PingController : ControllerBase
{
    private static readonly HashSet<string> ALLOWED_HOSTS = new() { "db01.internal", "db02.internal" };

    [HttpGet("/diag/ping")]
    public IActionResult Ping([FromQuery] string host) // taint: route
    {
        if (!ALLOWED_HOSTS.Contains(host))
        {
            return BadRequest();
        }
        using var proc = Process.Start("ping", "-n 1 " + host); // taint: sink
        return Ok(proc.StandardOutput.ReadToEnd());
    }
}
