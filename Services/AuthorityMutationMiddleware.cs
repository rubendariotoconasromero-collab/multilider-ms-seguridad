using Microsoft.EntityFrameworkCore;
using MSMultilider.Seguridad.Repositories;
namespace MSMultilider.Seguridad.Services;
public sealed class AuthorityMutationMiddleware(RequestDelegate next) {
    public async Task InvokeAsync(HttpContext context,ContextDatabase db) {
        if(context.GetEndpoint() is not null && !HttpMethods.IsGet(context.Request.Method) && !HttpMethods.IsHead(context.Request.Method) && !HttpMethods.IsOptions(context.Request.Method)) {
            await using var tx=await db.Database.BeginTransactionAsync(context.RequestAborted);
            await db.LockAuthority(context.RequestAborted);
            var output=context.Response.Body;
            await using var buffer=new MemoryStream();
            context.Response.Body=buffer;
            try {
                await next(context);
                if(context.Response.StatusCode<400) await tx.CommitAsync(context.RequestAborted);
                else await tx.RollbackAsync(context.RequestAborted);
                context.Response.Body=output;
                buffer.Position=0;
                await buffer.CopyToAsync(output,context.RequestAborted);
            } finally {context.Response.Body=output;}
        } else await next(context);
    }
}
