using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace Diag.Controllers;

[ApiController]
public class PingController : ControllerBase
{
    [HttpGet("/diag/ping")]
    public IActionResult Ping([FromQuery] string host) // taint: route
    {
        var args = "/c ping -n 1 " + host;
        using var proc = Process.Start("cmd.exe", args); // taint: sink
        return Ok(proc.StandardOutput.ReadToEnd());
    }
}
