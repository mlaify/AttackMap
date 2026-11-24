using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;

[ApiController]
public class OrdersController : ControllerBase
{
    [HttpGet("search")] // taint: route
    public IActionResult Search(string q, [FromServices] SqlConnection conn)
    {
        var cmd = new SqlCommand("SELECT * FROM Orders WHERE Name = @name", conn); // taint: sink
        cmd.Parameters.AddWithValue("@name", q);
        return Ok(cmd.ExecuteReader());
    }
}
