package com.urbanservices.web;

import com.urbanservices.model.ProviderProfile;
import com.urbanservices.model.UserAccount;
import com.urbanservices.model.UserRole;
import com.urbanservices.repository.ProviderProfileRepository;
import com.urbanservices.repository.UserAccountRepository;
import com.urbanservices.web.form.RegisterForm;
import jakarta.validation.Valid;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
public class AccountController {
    private final UserAccountRepository users;
    private final ProviderProfileRepository providers;
    private final PasswordEncoder passwordEncoder;
    private final String adminRegistrationCode;

    public AccountController(
        UserAccountRepository users,
        ProviderProfileRepository providers,
        PasswordEncoder passwordEncoder,
        @Value("${app.admin-registration-code:}") String adminRegistrationCode
    ) {
        this.users = users;
        this.providers = providers;
        this.passwordEncoder = passwordEncoder;
        this.adminRegistrationCode = adminRegistrationCode;
    }

    @GetMapping("/login")
    public String login(
        @org.springframework.web.bind.annotation.RequestParam(required = false) String accountType,
        Model model
    ) {
        model.addAttribute("accountType", isSupportedRole(accountType) ? accountType : "CUSTOMER");
        return "auth/login";
    }

    @GetMapping("/register")
    public String register(Model model) {
        if (!model.containsAttribute("registerForm")) {
            model.addAttribute("registerForm", new RegisterForm());
        }
        return "auth/register";
    }

    @PostMapping("/register")
    public String createAccount(
        @Valid @ModelAttribute("registerForm") RegisterForm form,
        BindingResult result,
        RedirectAttributes redirect
    ) {
        String email = form.getEmail() == null ? "" : form.getEmail().trim().toLowerCase();
        if (users.existsByEmailIgnoreCase(email)) {
            result.rejectValue("email", "duplicate", "An account with this email already exists.");
        }
        if (!form.getPassword().equals(form.getConfirmPassword())) {
            result.rejectValue("confirmPassword", "mismatch", "Passwords do not match.");
        }
        UserRole role = switch (form.getRole() == null ? "" : form.getRole()) {
            case "CUSTOMER" -> UserRole.CUSTOMER;
            case "PROVIDER" -> UserRole.PROVIDER;
            case "ADMIN" -> UserRole.ADMIN;
            default -> null;
        };
        if (role == null) {
            result.rejectValue("role", "invalid", "Choose Customer, Service Provider, or Administrator.");
        }
        if (role == UserRole.ADMIN && !isValidAdminInviteCode(form.getAdminInviteCode())) {
            result.rejectValue("adminInviteCode", "invalid",
                "A valid administrator invite code is required. Admin registration may be disabled.");
        }
        if (result.hasErrors()) return "auth/register";

        UserAccount user = new UserAccount();
        user.setName(form.getName().trim());
        user.setEmail(email);
        user.setPhone(form.getPhone().trim());
        user.setPasswordHash(passwordEncoder.encode(form.getPassword()));
        user.setRole(role);
        users.save(user);

        if (role == UserRole.PROVIDER) {
            ProviderProfile profile = new ProviderProfile();
            profile.setUser(user);
            profile.setExperience(form.getExperience());
            profile.setAvailability(form.getAvailability() == null || form.getAvailability().isBlank()
                ? "Monday to Saturday" : form.getAvailability().trim());
            providers.save(profile);
        }

        redirect.addFlashAttribute("success", "Your account has been created. Please sign in.");
        return "redirect:/login";
    }

    @GetMapping("/after-login")
    public String afterLogin(org.springframework.security.core.Authentication authentication) {
        if (authentication.getAuthorities().stream().anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"))) {
            return "redirect:/admin";
        }
        if (authentication.getAuthorities().stream().anyMatch(a -> a.getAuthority().equals("ROLE_PROVIDER"))) {
            return "redirect:/provider";
        }
        return "redirect:/customer";
    }

    private boolean isValidAdminInviteCode(String candidate) {
        if (adminRegistrationCode == null || adminRegistrationCode.isBlank() || candidate == null) return false;
        return MessageDigest.isEqual(
            adminRegistrationCode.getBytes(StandardCharsets.UTF_8),
            candidate.getBytes(StandardCharsets.UTF_8)
        );
    }

    private boolean isSupportedRole(String role) {
        return "CUSTOMER".equals(role) || "PROVIDER".equals(role) || "ADMIN".equals(role);
    }
}
