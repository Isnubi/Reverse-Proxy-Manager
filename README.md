<a name="readme-top"></a>

<!-- Projet Shields -->
[![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]
[![MIT License][license-shield]][license-url]
[![LinkedIn][linkedin-shield]][linkedin-url]

<!-- Replace these markers with infos - "Reverse-Proxy-Manager"-->

<!-- PROJECT LOGO -->
<br />
<div align="center">


<h3 align="center">Project Name</h3>
  <p align="center">
    <a href="https://github.com/ClubNix/Reverse-Proxy-Manager/"><strong>Explore the docs »</strong></a>
    <br />--------------------
    <br />
    <a href="https://github.com/ClubNix/Reverse-Proxy-Manager/issues">Report Bug</a>
    ·
    <a href="https://github.com/ClubNix/Reverse-Proxy-Manager/issues">Request Feature</a>
  </p>
</div>


<!-- TABLE OF CONTENTS -->
<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
      <ul>
        <li><a href="#built-with">Built With</a></li>
      </ul>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
      </ul>
    </li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#roadmap">Roadmap</a></li>
    <li><a href="#contributing">Contributing</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#contact">Contact</a></li>
  </ol>
</details>



<!-- ABOUT THE PROJECT -->
## About The Project

This project is a manager for Nginx reverse proxy. It allows you to manage your reverse proxy configuration files and to generate them automatically.

<p align="right">(<a href="#readme-top">back to top</a>)</p>



### Built With

* [![Bash][Bash-shield]][Bash-url]

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- GETTING STARTED -->
## Getting Started
<a name="getting-started"></a>

You can install **...** by following these steps.

### Prerequisites

1. Clone the repository on your computer.

    ```sh
    git clone https://github.com/ClubNix/Reverse-Proxy-Manager.git
    cd Reverse-Proxy-Manager
    ```
   
   * If **Git** is not installed, you can install it from [here](https://git-scm.com/downloads) or 
   download the repository as a zip file from [here](https://github.com/ClubNix/Reverse-Proxy-Manager/archive/refs/heads/master.zip)
        ```sh
        sudo apt install git
        ```


<!-- USAGE EXAMPLES -->
## Usage

You just have to launch the script as root (not sudo invoke).

```sh
chmod +x Reverse-Proxy-Manager.sh
./Reverse-Proxy-Manager.sh
```

At the first start, it will ask you to install Nginx if it is not already installed.
If Nginx is already installed, some paths will not be available. I recommend you to add the `/etc/nginx/certs` directory and execute the script to uninstall and reinstall Nginx with the script because of the recompilation of Nginx with specific modules.

<p align="right">(<a href="#readme-top">back to top</a>)</p>


<!-- ROADMAP -->
## Roadmap


See the [open issues](https://github.com/ClubNix/Reverse-Proxy-Manager/issues) for a full list of proposed features (and known issues).

<p align="right">(<a href="#readme-top">back to top</a>)</p>


<!-- CONTRIBUTING -->
## Contributing

Contributions are what make the open source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

If you have a suggestion that would make this better, please fork the repo and create a pull request. You can also simply open an issue with the tag "enhancement".
Don't forget to give the project a star! Thanks again!

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

<p align="right">(<a href="#readme-top">back to top</a>)</p>


<!-- LICENSE -->
## License

Distributed under the MIT License. See `LICENSE.md` for more information.

<p align="right">(<a href="#readme-top">back to top</a>)</p>


<!-- CONTACT -->
## Contact

Isnubi - [@Louis_Gambart](https://twitter.com/Louis_Gambart) - [contact@louis-gambart.fr](mailto:louis-gambart.fr)
<br>**Discord:** isnubi#6221

**Project Link:** [https://github.com/ClubNix/Reverse-Proxy-Manager](https://github.com/ClubNix/Reverse-Proxy-Manager)

<p align="right">(<a href="#readme-top">back to top</a>)</p>




<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->
[contributors-shield]: https://img.shields.io/github/contributors/ClubNix/Reverse-Proxy-Manager.svg?style=for-the-badge
[contributors-url]: https://github.com/ClubNix/Reverse-Proxy-Manager/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/ClubNix/Reverse-Proxy-Manager.svg?style=for-the-badge
[forks-url]: https://github.com/ClubNix/Reverse-Proxy-Manager/network/members
[stars-shield]: https://img.shields.io/github/stars/ClubNix/Reverse-Proxy-Manager.svg?style=for-the-badge
[stars-url]: https://github.com/ClubNix/Reverse-Proxy-Manager/stargazers
[issues-shield]: https://img.shields.io/github/issues/ClubNix/Reverse-Proxy-Manager.svg?style=for-the-badge
[issues-url]: https://github.com/ClubNix/Reverse-Proxy-Manager/issues
[license-shield]: https://img.shields.io/github/license/ClubNix/Reverse-Proxy-Manager.svg?style=for-the-badge
[license-url]: https://github.com/ClubNix/Reverse-Proxy-Manager/blob/master/LICENSE
[linkedin-shield]: https://img.shields.io/badge/-LinkedIn-black.svg?style=for-the-badge&logo=linkedin&colorB=555
[linkedin-url]: https://linkedin.com/in/louis-gambart
[Bash-shield]: https://img.shields.io/badge/Bash-121011?style=for-the-badge&logo=gnu-bash&logoColor=white
[Bash-url]: https://www.gnu.org/software/bash/
[Twitter-shield]: https://img.shields.io/twitter/follow/Louis_Gambart?style=social
[Twitter-url]: https://twitter.com/Louis_Gambart/
