<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;

class SecurityController extends AbstractController
{
    #[Route('/login', name: 'app_login')]
    public function index(AuthenticationUtils $au): Response
    {
        if($this->getUser() !== null || $this->getUser() !== ' '){
            return $this->redirectToRoute('app_dashboard');

        }
        $error = $au->getLastAuthenticationError();
        $lastUsername = $au->getLastUsername();
        return $this->render('security/index.html.twig', [
            'last_username' => $lastUsername,
            'error' => $error
        ]);
      
    }

    #[Route('/logout', name: 'app_logout')]
    public function logout(): void
    {
    
    }
}
