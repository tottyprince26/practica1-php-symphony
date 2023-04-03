<?php

namespace App\Controller;

use App\Security\AppCustomAuthenticator;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Http\Authentication\UserAuthenticatorInterface;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\HttpFoundation\Request;
use App\Form\RegistroFormType;
use App\Entity\User;

class RegistroController extends AbstractController
{
    #[Route('/registro', name: 'app_registro')]
    public function register(Request $req, UserPasswordHasherInterface $uphai, UserAuthenticatorInterface $uai,
    AppCustomAuthenticator $aca, EntityManagerInterface $emi) : Response
    {
        $user = new User();
        $form = $this -> createForm(RegistroFormType::class, $user);
        $form-> handleRequest($req);
        if($form -> isSubmitted() && $form -> isValid()){
            $user -> setPassword($uphai -> hashPassword($user, $form -> get('password') -> getData()));
            $emi -> persist($user);
            $emi -> flush();    
            return $uai -> authenticateUser($user, $aca, $req);
        }
        return $this -> render('registro/index.html.twig', [
            'form' => $form -> createView()
        ]);
    }
}
