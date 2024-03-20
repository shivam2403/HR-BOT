import { createContext, useContext, useState } from "react";


const UserContext=createContext();

export const UserProvider = ({ children }) => {
    const storedUser = localStorage.getItem('user');
    const initialUser = storedUser ? JSON.parse(storedUser) : null;
  
    const [user, setUser] = useState(initialUser);
  
    const loginUser = (userData) => {
      setUser(userData);
      localStorage.setItem('user', JSON.stringify(userData));
    };
  
    const logoutUser = () => {
      setUser(null);
      localStorage.removeItem('user');
    };
  
    return (
      <UserContext.Provider value={{ user, loginUser, logoutUser }}>
        {children}
      </UserContext.Provider>
    );
  };
  

export const useUser = () => {
    const context = useContext(UserContext);
    if (!context) {
      throw new Error('useUser must be used within a UserProvider');
    }
    return context;
}


