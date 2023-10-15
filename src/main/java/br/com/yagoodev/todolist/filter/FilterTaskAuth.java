package br.com.yagoodev.todolist.filter;

import java.io.IOException;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import at.favre.lib.crypto.bcrypt.BCrypt;
import at.favre.lib.crypto.bcrypt.BCrypt.Result;
import br.com.yagoodev.todolist.user.IUserRepository;
import br.com.yagoodev.todolist.user.UserModel;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class FilterTaskAuth extends OncePerRequestFilter {

  @Autowired
  private IUserRepository userRepositoryService;

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {

    var serverletPath = request.getServletPath();

    if (serverletPath.startsWith("/tasks/")) {
      var authorization = request.getHeader("Authorization");

      var authEncoded = authorization.substring("Basic".length()).trim();

      byte[] authDecode = Base64.getDecoder().decode(authEncoded);

      String authString = new String(authDecode);

      String[] credentials = authString.split(":");

      String username = credentials[0];
      String password = credentials[1];

      UserModel userInDatabase = this.userRepositoryService.findByUsername(username);

      if (userInDatabase == null) {
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
        return;
      }

      Result verifiedPassword = BCrypt.verifyer().verify(password.toCharArray(), userInDatabase.getPassword());

      if (verifiedPassword.verified) {
        request.setAttribute("userId", userInDatabase.getId());

        filterChain.doFilter(request, response);
      } else {
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
      }

      return;
    }

    filterChain.doFilter(request, response);
  }

}