<?php

namespace App\Controller;

use App\Entity\User;
use App\Form\RegistrationFormType;
use App\Form\UpdateUserForm;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;
use Symfony\Component\Security\Core\Encoder\UserPasswordEncoderInterface; 
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\Extension\Core\Type\CheckboxType;
use Symfony\Component\Form\Extension\Core\Type\PasswordType;
use Symfony\Component\Form\Extension\Core\Type\TextType;
use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Component\OptionsResolver\OptionsResolver;
use Symfony\Component\Validator\Constraints\IsTrue;
use Symfony\Component\Validator\Constraints\Length;
use Symfony\Component\Validator\Constraints\Data;

use Symfony\Component\Validator\Constraints\NotBlank;
use Symfony\Component\Form\Extension\Core\Type\RepeatedType;

class SecurityController extends AbstractController
{
    /**
     * @Route("/", name="login")
     */
    public function index(Request $request,AuthenticationUtils $utils):Response
    {   
        if ($this->getUser()) {
            return $this->redirectToRoute('home');
        }
        $error = $utils->getLastAuthenticationError();
        $last_email = $utils->getLastUsername();
        return $this->render('security/index.html.twig',['error'=>$error,'last_email'=>$last_email]);
    }

    /**
     * @Route("/logout", name="logout")
     */
    public function logout()
    {
        throw new \Exception('');
    }

    /**
     * @Route("/delete", name="delete")
     */
    public function delete(request $request):Response{
        
        $session = $this->get('session');
        $session = new Session();
        $session->invalidate();

        $entityManager = $this->getDoctrine()->getManager();
        $usr = $this->getUser();
        $userId = $usr->getId();
        $user = $entityManager->getRepository(User::class)->find($userId);
        $entityManager->remove($user);
        $entityManager->flush();
        $this->get('security.token_storage')->setToken(null);
        
        return $this->redirectToRoute('login');
    }


    /**
     * @Route("/home", name="home")
     */
    public function home(request $request,UserPasswordEncoderInterface $passwordEncoder): Response
    {
        $usr = $this->getUser();
        $defaultData = ['updateForm' => ''];
        $form = $this->createFormBuilder($defaultData)
        ->add('email', TextType::class, [
            'data'=>$usr->getEmail()
            ]
        )
        ->add('username',TextType::class, [
            'data'=>$usr->getUsername()
            ]
        )
        ->add('Currentpassword',PasswordType::class,[
            'constraints' => [               
                new NotBlank([
                    'message' => 'Please enter a password',
                ]),
                new Length([
                    'min' => 6,
                    'minMessage' => 'Your password should be at least {{ limit }} characters',
                    'max' => 4096,
                ]),
            ],
        ])
        
        ->add('password', RepeatedType::class, [
            'constraints' =>[new Length([
                'min' => 6,
                'minMessage' => 'Your password should be at least {{ limit }} characters',
                'max' => 4096,
            ]),],
            'type' => PasswordType::class,
            'invalid_message' => 'The password fields must match.',
            'options' => ['attr' => ['class' => 'password-field']],
            'required' => true,
            'first_options'  => ['label' => 'Password'],
            'second_options' => ['label' => 'Repeat Password'],  
            
        ])
        ->getForm();

        
        $form->handleRequest($request);


        if ($form->isSubmitted() && $form->isValid()) {
            
            $entityManager = $this->getDoctrine()->getManager();
            $userId = $usr->getId();
            $user = $entityManager->getRepository(User::class)->find($userId);
            $user1 = new User();
            $currentPassword = $form->get('Currentpassword')->getData();
            if($passwordEncoder->isPasswordValid($user, $currentPassword)){
                $entityManager = $this->getDoctrine()->getManager();
                $user->setUsername($form->get('username')->getData());
                $user->setEmail($form->get('email')->getData());
                $user->setPassword($passwordEncoder->encodePassword($user1,$form->get('password')->getData()));
                $entityManager->flush();
                return $this->redirectToRoute('/');
            }else{
                return $this->render('index.html.twig',[
                    'error'=>'please verify entred password',
                    'UpdateUserForm' => $form->createView(),
                ]);
            }
            
            $entityManager->flush();
            return $this->redirectToRoute('home');

        }

        return $this->render('index.html.twig',
        [
            'error' => '',
            'UpdateUserForm' => $form->createView(),
        ]);
    }

    /**
     * @Route("/register", name="register")
     */
    public function register(Request $request, UserPasswordEncoderInterface $passwordEncoder): Response
    {
        $user = new User();
        $form = $this->createForm(RegistrationFormType::class, $user);
        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {
            // encode the plain password
            $user->setPassword(
                $passwordEncoder->encodePassword(
                    $user,
                    $form->get('plainPassword')->getData()
                )
            );

            $entityManager = $this->getDoctrine()->getManager();
            $entityManager->persist($user);
            $entityManager->flush();

            return $this->redirectToRoute('logout');
        }

        return $this->render('registration/register.html.twig', [
            'registrationForm' => $form->createView(),
        ]);
    }

    

}
