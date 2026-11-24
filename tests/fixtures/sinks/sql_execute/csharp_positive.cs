using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;

[ApiController]
public class OrdersController : ControllerBase
{
    [HttpGet("search")] // taint: route
    public IActionResult Search(string q)
    {
        var cmd = new SqlCommand("SELECT * FROM Orders WHERE Name = '" + q + "'"); // taint: sink
        return Ok(cmd.ExecuteReader());
    }
}
